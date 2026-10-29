use rbitcoin_net::socks::{
    dial_isolated, socks5_connect, socks5_connect_domain, Dialer, ProxyCreds,
};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tokio::net::TcpListener;

#[tokio::test]
async fn socks5_connect_ipv4_against_fake_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let target = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 8333));

    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut ver_n = [0u8; 2];
        s.read_exact(&mut ver_n).await.unwrap();
        assert_eq!(ver_n[0], 5, "SOCKS version");
        let nmethods = ver_n[1] as usize;
        let mut methods = vec![0u8; nmethods];
        s.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&0x00), "NOAUTH offered, got {methods:?}");
        s.write_all(&[5, 0x00]).await.unwrap();

        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], 5);
        assert_eq!(hdr[1], 1, "CONNECT");
        assert_eq!(hdr[2], 0);
        assert_eq!(hdr[3], 1, "ATYP IPv4");
        let mut addr = [0u8; 4];
        s.read_exact(&mut addr).await.unwrap();
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();
        assert_eq!(addr, [203, 0, 113, 7]);
        assert_eq!(u16::from_be_bytes(port), 8333);

        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();

        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });

    let mut stream = socks5_connect(proxy, target, None).await.unwrap();
    stream.write_all(&[0xab]).await.unwrap();
    let mut echo = [0u8; 1];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo, [0xab]);
    server.await.unwrap();
}

#[tokio::test]
async fn socks5_connect_domain_does_not_resolve_locally() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let host = "seed.example";
    let port = 8333u16;

    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut ver_n = [0u8; 2];
        s.read_exact(&mut ver_n).await.unwrap();
        let nmethods = ver_n[1] as usize;
        let mut methods = vec![0u8; nmethods];
        s.read_exact(&mut methods).await.unwrap();
        s.write_all(&[5, 0x00]).await.unwrap();

        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], 5);
        assert_eq!(hdr[1], 1, "CONNECT");
        assert_eq!(hdr[2], 0);
        assert_eq!(hdr[3], 3, "ATYP domain; must not resolve locally");
        let mut n = [0u8; 1];
        s.read_exact(&mut n).await.unwrap();
        let mut name = vec![0u8; n[0] as usize];
        s.read_exact(&mut name).await.unwrap();
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        assert_eq!(name, b"seed.example");
        assert_eq!(u16::from_be_bytes(p), 8333);

        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    });

    socks5_connect_domain(proxy, host, port, None)
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn socks_creds_offer_only_userpass() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let target = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 8333));
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut ver_n = [0u8; 2];
        s.read_exact(&mut ver_n).await.unwrap();
        let nmethods = ver_n[1] as usize;
        let mut methods = vec![0u8; nmethods];
        s.read_exact(&mut methods).await.unwrap();
        assert_eq!(
            methods,
            vec![0x02],
            "creds must not offer NOAUTH: {methods:?}"
        );
        s.write_all(&[5, 0x02]).await.unwrap();
        let mut ver = [0u8; 1];
        s.read_exact(&mut ver).await.unwrap();
        let mut ulen = [0u8; 1];
        s.read_exact(&mut ulen).await.unwrap();
        let mut user = vec![0u8; ulen[0] as usize];
        s.read_exact(&mut user).await.unwrap();
        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        s.read_exact(&mut pass).await.unwrap();
        s.write_all(&[1, 0]).await.unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 1);
        let mut addr = [0u8; 4];
        s.read_exact(&mut addr).await.unwrap();
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    });
    let d = Dialer::socks(proxy, false);
    d.connect(target).await.unwrap();
    server.await.unwrap();
}

async fn accept_domain_connect(
    listener: TcpListener,
    want_host: impl AsRef<[u8]> + Send,
    want_port: u16,
) {
    let want_host = want_host.as_ref().to_vec();
    let (mut s, _) = listener.accept().await.unwrap();
    let mut ver_n = [0u8; 2];
    s.read_exact(&mut ver_n).await.unwrap();
    let nmethods = ver_n[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await.unwrap();
    if methods.contains(&0x02) {
        s.write_all(&[5, 0x02]).await.unwrap();
        let mut ver = [0u8; 1];
        s.read_exact(&mut ver).await.unwrap();
        let mut ulen = [0u8; 1];
        s.read_exact(&mut ulen).await.unwrap();
        let mut user = vec![0u8; ulen[0] as usize];
        s.read_exact(&mut user).await.unwrap();
        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        s.read_exact(&mut pass).await.unwrap();
        s.write_all(&[1, 0]).await.unwrap();
    } else {
        s.write_all(&[5, 0x00]).await.unwrap();
    }
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[3], 3, "ATYP domain");
    let mut n = [0u8; 1];
    s.read_exact(&mut n).await.unwrap();
    let mut name = vec![0u8; n[0] as usize];
    s.read_exact(&mut name).await.unwrap();
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await.unwrap();
    assert_eq!(name, want_host);
    assert_eq!(u16::from_be_bytes(p), want_port);
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
}

#[tokio::test]
async fn dialer_connect_domain_covers_socks_and_direct() {
    let host = "seed.example";
    let port = 8333u16;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let server = tokio::spawn(accept_domain_connect(listener, b"seed.example", port));
    Dialer::socks(proxy, true)
        .connect_domain(host, port)
        .await
        .unwrap();
    server.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let server = tokio::spawn(accept_domain_connect(listener, b"seed.example", port));
    Dialer::socks(proxy, false)
        .connect_domain(host, port)
        .await
        .unwrap();
    server.await.unwrap();

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });
    let mut stream = Dialer::Direct
        .connect_domain("127.0.0.1", echo_addr.port())
        .await
        .unwrap();
    stream.write_all(&[0x42]).await.unwrap();
    let mut got = [0u8; 1];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, [0x42]);
    server.await.unwrap();
}

async fn serve_userpass_ipv4(
    s: &mut tokio::net::TcpStream,
    want_ip: [u8; 4],
    want_port: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut ver_n = [0u8; 2];
    s.read_exact(&mut ver_n).await.unwrap();
    assert_eq!(ver_n[0], 5);
    let nmethods = ver_n[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&0x02), "USERPASS offered, got {methods:?}");
    s.write_all(&[5, 0x02]).await.unwrap();

    let mut ver = [0u8; 1];
    s.read_exact(&mut ver).await.unwrap();
    assert_eq!(ver[0], 1);
    let mut ulen = [0u8; 1];
    s.read_exact(&mut ulen).await.unwrap();
    let mut user = vec![0u8; ulen[0] as usize];
    s.read_exact(&mut user).await.unwrap();
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).await.unwrap();
    let mut pass = vec![0u8; plen[0] as usize];
    s.read_exact(&mut pass).await.unwrap();
    s.write_all(&[1, 0]).await.unwrap();

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[3], 1);
    let mut addr = [0u8; 4];
    s.read_exact(&mut addr).await.unwrap();
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await.unwrap();
    assert_eq!(addr, want_ip);
    assert_eq!(u16::from_be_bytes(p), want_port);
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    (user, pass)
}

#[tokio::test]
async fn socks5_username_password_seen_by_fake_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let target = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 8333));
    let creds = ProxyCreds {
        username: b"alice".to_vec(),
        password: b"secret".to_vec(),
    };
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        serve_userpass_ipv4(&mut s, [198, 51, 100, 1], 8333).await
    });
    socks5_connect(proxy, target, Some(&creds)).await.unwrap();
    let (user, pass) = server.await.unwrap();
    assert_eq!(user, b"alice");
    assert_eq!(pass, b"secret");
}

#[tokio::test]
async fn dial_isolated_uses_new_creds_each_call() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let target = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 2), 8333));
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut s, _) = listener.accept().await.unwrap();
            let creds = serve_userpass_ipv4(&mut s, [198, 51, 100, 2], 8333).await;
            tx.send(creds).await.unwrap();
        }
    });
    dial_isolated(proxy, target).await.unwrap();
    dial_isolated(proxy, target).await.unwrap();
    let (u1, _) = rx.recv().await.unwrap();
    let (u2, _) = rx.recv().await.unwrap();
    server.await.unwrap();
    assert_ne!(u1, u2, "each isolated dial must use fresh SOCKS creds");
    assert!(!u1.is_empty() && !u2.is_empty());
}

#[tokio::test]
async fn randomize_off_reuses_stable_userpass_per_dialer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let target = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 3), 8333));
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut s, _) = listener.accept().await.unwrap();
            let creds = serve_userpass_ipv4(&mut s, [198, 51, 100, 3], 8333).await;
            tx.send(creds).await.unwrap();
        }
    });
    let d = Dialer::socks(proxy, false);
    d.connect(target).await.unwrap();
    d.connect(target).await.unwrap();
    let (u1, p1) = rx.recv().await.unwrap();
    let (u2, p2) = rx.recv().await.unwrap();
    server.await.unwrap();
    assert_eq!(u1, u2, "randomize=0 must keep one SOCKS username");
    assert_eq!(p1, p2, "randomize=0 must keep one SOCKS password");
}

async fn splice_one_socks(listener: TcpListener, saw: tokio::sync::oneshot::Sender<SocketAddr>) {
    let (mut c, _) = listener.accept().await.unwrap();
    let mut ver_n = [0u8; 2];
    c.read_exact(&mut ver_n).await.unwrap();
    let nmethods = ver_n[1] as usize;
    let mut methods = vec![0u8; nmethods];
    c.read_exact(&mut methods).await.unwrap();
    if methods.contains(&0x02) {
        c.write_all(&[5, 0x02]).await.unwrap();
        let mut ver = [0u8; 1];
        c.read_exact(&mut ver).await.unwrap();
        let mut ulen = [0u8; 1];
        c.read_exact(&mut ulen).await.unwrap();
        let mut user = vec![0u8; ulen[0] as usize];
        c.read_exact(&mut user).await.unwrap();
        let mut plen = [0u8; 1];
        c.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        c.read_exact(&mut pass).await.unwrap();
        c.write_all(&[1, 0]).await.unwrap();
    } else {
        c.write_all(&[5, 0x00]).await.unwrap();
    }
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[1], 1);
    let dest = match hdr[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await.unwrap();
            let mut p = [0u8; 2];
            c.read_exact(&mut p).await.unwrap();
            SocketAddr::from((Ipv4Addr::new(a[0], a[1], a[2], a[3]), u16::from_be_bytes(p)))
        }
        _ => panic!("test splice expects IPv4 CONNECT"),
    };
    let mut peer = TcpStream::connect(dest).await.unwrap();
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let _ = saw.send(dest);
    let _ = tokio::io::copy_bidirectional(&mut c, &mut peer).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_dial_uses_proxy_when_set() {
    use bitcoin::p2p::Magic;
    use rbitcoin_net::peer::{connect_and_handshake_timed, HandshakePolicy, HANDSHAKE_TIMEOUT};
    use std::time::Duration;

    let bitcoin_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = bitcoin_l.local_addr().unwrap();
    let inbound = tokio::spawn(async move {
        let (stream, from) = bitcoin_l.accept().await.unwrap();
        connect_and_handshake_timed(
            Duration::from_secs(5),
            stream,
            Magic::REGTEST,
            peer_addr,
            from,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
    });

    let socks_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks_l.local_addr().unwrap();
    let (saw_tx, saw_rx) = tokio::sync::oneshot::channel();
    let splice = tokio::spawn(splice_one_socks(socks_l, saw_tx));

    let stream = Dialer::socks(proxy, true).connect(peer_addr).await.unwrap();
    assert_eq!(saw_rx.await.unwrap(), peer_addr);

    connect_and_handshake_timed(
        Duration::from_secs(5),
        stream,
        Magic::REGTEST,
        proxy,
        peer_addr,
        0,
        false,
        "/rbitcoin:test/",
        HandshakePolicy::plain(),
    )
    .await
    .unwrap();
    inbound.await.unwrap().unwrap();
    splice.abort();

    let direct_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let direct_addr = direct_l.local_addr().unwrap();
    let inbound = tokio::spawn(async move {
        let (stream, from) = direct_l.accept().await.unwrap();
        connect_and_handshake_timed(
            HANDSHAKE_TIMEOUT,
            stream,
            Magic::REGTEST,
            direct_addr,
            from,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
    });
    let stream = Dialer::Direct.connect(direct_addr).await.unwrap();
    connect_and_handshake_timed(
        Duration::from_secs(5),
        stream,
        Magic::REGTEST,
        direct_addr,
        direct_addr,
        0,
        false,
        "/rbitcoin:test/",
        HandshakePolicy::plain(),
    )
    .await
    .unwrap();
    inbound.await.unwrap().unwrap();
}

#[tokio::test]
async fn dial_onion_uses_socks_domain_connect() {
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let server = tokio::spawn(accept_domain_connect(
        listener,
        b"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
        8333,
    ));
    Dialer::socks(proxy, false)
        .connect_net(onion)
        .await
        .unwrap();
    server.await.unwrap();

    assert!(
        Dialer::Direct.connect_net(onion).await.is_err(),
        "onion must not TcpStream::connect / local DNS"
    );
}

#[tokio::test]
async fn onion_only_dialer_keeps_clearnet_direct() {
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let onion_proxy = socks.local_addr().unwrap();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let _ = echo.accept().await;
    });
    let d = Dialer::with_proxies(None, Some(onion_proxy), false);
    d.connect(echo_addr).await.unwrap();
    echo_task.await.unwrap();

    let server = tokio::spawn(accept_domain_connect(
        socks,
        b"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
        8333,
    ));
    d.connect_net(onion).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn connect_isolated_net_never_dials_direct() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use rbitcoin_net::ephemeral::send_tx_isolated;
    use rbitcoin_net::NetAddr;

    let tx = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let magic = bitcoin::Network::Bitcoin.magic();
    let onion = NetAddr::Onion {
        pk: [0x11; 32],
        port: 8333,
    };
    let i2p = NetAddr::I2p {
        dest: [0x22; 32],
        port: 0,
    };
    let err = send_tx_isolated(&Dialer::Direct, onion, magic, tx.clone(), "/rbitcoin-test/")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("onion dial requires SOCKS"),
        "{err}"
    );
    let err = send_tx_isolated(&Dialer::Direct, i2p, magic, tx, "/rbitcoin-test/")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("i2p dial requires SAM"), "{err}");

    let bare = Dialer::Socks {
        proxy: None,
        onion: None,
        randomize: true,
        shared_creds: None,
        connect_floor: std::time::Duration::from_secs(30),
    };
    let err = bare
        .connect_isolated_net(NetAddr::Onion {
            pk: [0x33; 32],
            port: 8333,
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("onion dial requires SOCKS"),
        "{err}"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ip = listener.local_addr().unwrap();
    let onion_only = Dialer::with_proxies(None, Some(ip), true);
    for dialer in [&Dialer::Direct, &onion_only] {
        let err = dialer
            .connect_isolated_net(NetAddr::Ip(ip))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("isolated broadcast needs --proxy"),
            "{dialer:?}: {err}"
        );
    }

    let onion = NetAddr::Onion {
        pk: [0x44; 32],
        port: 18444,
    };
    let host = onion.host_str();
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks.local_addr().unwrap();
    let server = tokio::spawn(accept_domain_connect(socks, host.into_bytes(), 18444));
    let stream = Dialer::socks(proxy, true)
        .connect_isolated_net(onion)
        .await
        .unwrap();
    assert!(stream.peer_addr().is_ok());
    server.await.unwrap();

    let cjdns_listener = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let cjdns = NetAddr::Cjdns {
        ip: std::net::Ipv6Addr::LOCALHOST,
        port: cjdns_listener.local_addr().unwrap().port(),
    };
    for dialer in [&Dialer::Direct, &Dialer::socks(proxy, true)] {
        let err = dialer.connect_isolated_net(cjdns).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("isolated broadcast never dials cjdns"),
            "{dialer:?}: {err}"
        );
    }

    for listener in [listener, cjdns_listener] {
        assert!(
            tokio::time::timeout(std::time::Duration::ZERO, listener.accept())
                .await
                .is_err(),
            "a direct connection reached {:?}",
            listener.local_addr()
        );
    }
}
