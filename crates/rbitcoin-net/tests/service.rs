use bitcoin::p2p::Magic;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::error::NetError;
use rbitcoin_net::peers::PeerConnType;
use rbitcoin_net::service::*;
use rbitcoin_query::Query;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[test]
fn magic_for_all_networks() {
    assert_eq!(
        magic_for_params(&ChainParams::mainnet()),
        Magic::from(bitcoin::Network::Bitcoin)
    );
    assert_eq!(
        magic_for_params(&ChainParams::testnet()),
        Magic::from(bitcoin::Network::Testnet)
    );
    assert_eq!(
        magic_for_params(&ChainParams::signet()),
        Magic::from(bitcoin::Network::Signet)
    );
    assert_eq!(magic_for_params(&ChainParams::regtest()), Magic::REGTEST);
}

#[test]
fn custom_signet_uses_challenge_derived_magic() {
    use bitcoin::ScriptBuf;

    let challenge = ScriptBuf::from_bytes(vec![0x51]);
    let params = ChainParams::custom_signet(challenge, 60).unwrap();
    assert_eq!(
        magic_for_params(&params),
        Magic::from_bytes([0x54, 0xd2, 0x6f, 0xbd])
    );
}

/// A feeler does not use `prepare_outbound_session`. It still must not
/// open a socket to an address that misbehaved.
#[tokio::test]
async fn feeler_does_not_dial_a_discouraged_address() {
    let peers = rbitcoin_net::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    peers.clock.set_mock(1_700_000_000_i64);
    peers.on_clock_jump();
    let addr = std::net::SocketAddr::from(([1, 2, 3, 4], 8333));
    peers.note_misbehavior_addr(addr.ip());
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("feeler-discouraged");
    let (_tx, rx) = tokio::sync::oneshot::channel();
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        run_outbound_session_with_abort(
            rbitcoin_net::peers::DialTarget::Socket(addr),
            None,
            Magic::REGTEST,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            std::sync::Arc::new(hub),
            peers,
            "/rbitcoin:test/".into(),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rbitcoin_net::peers::PeerConnType::Feeler,
            rx,
            rbitcoin_net::socks::Dialer::Direct,
        ),
    )
    .await;
    let _ = std::fs::remove_dir_all(dir.path());
    let err = result
        .expect("a refused feeler returns before the connect")
        .unwrap_err();
    assert!(
        matches!(err, NetError::Protocol("discouraged")),
        "feeler dialed a discouraged address, got {err:?}"
    );
}

/// `--proxy` turns the DNS seeds into addr-fetch dials by name. The
/// proxy resolves the name, so the node holds no address for it.
#[tokio::test]
async fn proxied_dns_seed_dials_by_name_through_socks() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let socks = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 2];
        s.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0u8; greeting[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        if methods.contains(&0x02) {
            s.write_all(&[5, 0x02]).await.unwrap();
            let mut ulen = [0u8; 2];
            s.read_exact(&mut ulen).await.unwrap();
            let mut user = vec![0u8; ulen[1] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[1, 0]).await.unwrap();
        } else {
            s.write_all(&[5, 0x00]).await.unwrap();
        }
        let mut req = [0u8; 5];
        s.read_exact(&mut req).await.unwrap();
        assert_eq!(req[3], 3, "ATYP domain");
        let mut host = vec![0u8; req[4] as usize];
        s.read_exact(&mut host).await.unwrap();
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        (String::from_utf8(host).unwrap(), u16::from_be_bytes(port))
    });
    let peers = rbitcoin_net::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("proxied-dns-seed");
    let (_tx, rx) = tokio::sync::oneshot::channel();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        run_outbound_session_with_abort(
            rbitcoin_net::peers::DialTarget::Domain {
                host: "seed.example".into(),
                port: 8333,
            },
            None,
            Magic::REGTEST,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            std::sync::Arc::new(hub),
            peers,
            "/rbitcoin:test/".into(),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rbitcoin_net::peers::PeerConnType::AddrFetch,
            rx,
            rbitcoin_net::socks::Dialer::socks(proxy, false),
        ),
    )
    .await;
    let _ = std::fs::remove_dir_all(dir.path());
    assert!(
        result
            .expect("the session ends when the proxy closes")
            .is_err(),
        "the proxy closed before VERSION"
    );
    assert_eq!(socks.await.unwrap(), ("seed.example".to_string(), 8333));
}

/// One datadir, two node lifetimes. The first is dropped without
/// shutdown. The second binds loopback as with onion listen, adds a
/// second listener, and shuts down with one session task that finishes
/// in the grace window and one that would linger.
#[tokio::test]
async fn service_listen_shutdown() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-p2p-listen-shutdown-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let node = P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        Query::open_or_create_tiny(&dir).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    assert!(node.hub.shared_arc().is_some());
    let t0 = std::time::Instant::now();
    drop(node);
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "dropping the node must abort connect-retry without waiting out the runtime"
    );

    let mut node = P2PNode::start_with_dialer(
        "127.0.0.1:0".parse().unwrap(),
        Query::open_or_create_tiny(&dir).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(onion)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::socks::Dialer::Direct,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    assert_eq!(node.local_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    assert_ne!(node.local_addr.port(), 0);
    let extra = node
        .add_listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert_ne!(extra, node.local_addr);
    assert!(std::net::TcpStream::connect(extra).is_ok());

    let done = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&done);
    node.tasks.push(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        flag.store(true, Ordering::SeqCst);
    }));
    node.tasks.push(tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }));
    let t0 = std::time::Instant::now();
    node.shutdown().await;
    assert!(
        done.load(Ordering::SeqCst),
        "shutdown lets a task that finishes within the grace window finish"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "shutdown must not wait out a 30s session task"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_outbound_only_dials_without_listener() {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-outbound-only-{n}"));
    std::fs::create_dir_all(dir.join("seed")).unwrap();
    std::fs::create_dir_all(dir.join("follow")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("seed")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("follow")).unwrap();
    let params = ChainParams::regtest();
    let seeder = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(seed)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let mut follower = P2PNode::start_outbound_only(
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(follow)/".into(),
        0,
        rbitcoin_net::socks::Dialer::Direct,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    assert_eq!(
        follower.local_addr,
        "127.0.0.1:0".parse().unwrap(),
        "outbound-only must not bind a P2P port"
    );
    assert_eq!(follower.max_inbound, 0);
    let inbound_err = follower
        .peers
        .addconnection(seeder.local_addr, PeerConnType::Inbound)
        .unwrap_err();
    assert!(
        inbound_err.contains("inbound"),
        "addconnection inbound must refuse: {inbound_err}"
    );

    follower.follow_from(seeder.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        if follower.follow_live_count() >= 1 && !seeder.peers.snapshot().is_empty() {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    seeder.shutdown().await;
    follower.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(linked, "outbound-only follower must handshake the seeder");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listen_onion_loopback_inbound_handshake() {
    use bitcoin::p2p::Magic;
    use rbitcoin_net::peer::{connect_and_handshake_timed, HandshakePolicy};
    use tokio::net::TcpStream;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-listen-onion-hs-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let node = P2PNode::start_with_dialer(
        "127.0.0.1:0".parse().unwrap(),
        q,
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(onion)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::socks::Dialer::Direct,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let stream = TcpStream::connect(node.local_addr).await.unwrap();
    let _hs = connect_and_handshake_timed(
        Duration::from_secs(5),
        stream,
        Magic::REGTEST,
        node.local_addr,
        node.local_addr,
        0,
        false,
        "/rbitcoin:test/",
        HandshakePolicy::plain(),
    )
    .await
    .unwrap();
    let mut inbound = false;
    for _ in 0..200 {
        if node.peers.snapshot().iter().any(|p| p.inbound) {
            inbound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        inbound,
        "loopback client must show as inbound in getpeerinfo"
    );
}

/// The 2 s redial pass must not stack a dial that is still connecting,
/// and must not lose the target to one that never finishes. A SOCKS
/// proxy that accepts and never answers holds the first dial in
/// `connect_net`: later passes skip it until the connect times out, then
/// dial again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redial_skips_a_connect_target_still_dialling() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepts);
    let stall = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = proxy.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(sock);
        }
    });
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-redial-in-flight-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let connect_bound = Duration::from_millis(500);
    let node = P2PNode::start_outbound_only(
        Query::open_or_create_tiny(&dir).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(redial)/".into(),
        0,
        rbitcoin_net::socks::Dialer::socks(proxy_addr, false).with_connect_floor(connect_bound),
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    node.peers.set_connect_addrs(vec![rbitcoin_net::NetAddr::Ip(
        "127.0.0.1:18444".parse().unwrap(),
    )]);
    node.peers.redial_remembered();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while accepts.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the first dial never reached the proxy"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for _ in 0..3 {
        node.peers.redial_remembered();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "a dial still connecting must not be dialled again"
    );
    // The stalled connect times out and frees the target for the next pass.
    let deadline = std::time::Instant::now() + connect_bound * 3;
    while accepts.load(Ordering::SeqCst) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "a connect that never finishes must time out and be redialled"
        );
        node.peers.redial_remembered();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stall.abort();
    drop(node);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn outbound_connect_timeout_is_eight_seconds() {
    assert_eq!(OUTBOUND_CONNECT_TIMEOUT, Duration::from_secs(8));
}

#[test]
fn accept_retries_a_full_fd_table_and_stops_on_a_dead_listener() {
    let aborted = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "reset");
    let interrupted = std::io::Error::new(std::io::ErrorKind::Interrupted, "signal");
    let emfile = std::io::Error::from_raw_os_error(24);
    let enfile = std::io::Error::from_raw_os_error(23);
    let dead = std::io::Error::new(std::io::ErrorKind::InvalidInput, "closed");
    assert!(!accept_error_ends_listen(&aborted));
    assert!(!accept_error_ends_listen(&interrupted));
    assert!(!accept_error_ends_listen(&emfile));
    assert!(!accept_error_ends_listen(&enfile));
    assert!(accept_error_ends_listen(&dead));
}

#[tokio::test]
async fn shutdown_finishes_without_the_dial_grace() {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-shutdown-grace-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    let node = P2PNode::start_outbound_only(
        Query::open_or_create_tiny(&dir).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:test/".into(),
        0,
        rbitcoin_net::socks::Dialer::Direct,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let t0 = tokio::time::Instant::now();
    node.shutdown().await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(200),
        "dial and retry must observe shutdown, took {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
