use rbitcoin_net::{AddrMan, Dialer, PeerConnType, TipEvent};
use rbitcoin_node::config::{parse_btc_to_sat, NodeConfig, NodeEnv};
use rbitcoin_node::run::*;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
fn tiny_regtest(dir: impl AsRef<std::path::Path>) -> NodeConfig {
    NodeConfig::default()
        .with_datadir(dir.as_ref())
        .with_network(rbitcoin_primitives::Network::Regtest)
        .with_tiny_heads()
}

/// Perf (5s) and RPC-stop (50ms) ticks must still evaluate stale redial.
/// A one-shot sleep in the same `select!` is reset on every such wake.
/// `--sh-index` off still binds Electrum/Esplora. Address methods fail
/// closed inside the servers; the listeners themselves are not the gate.
#[test]
fn listeners_ready_without_sh_index() {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-shoff-listen-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let gates = enter_tip_mode(&q, None, false);
    assert!(gates.tip_follow_ready);
    assert!(
        gates.sh_tip_ready,
        "Electrum/Esplora bind when --sh-index is off"
    );
    assert!(!q.sh_index_enabled());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stale_follow_needs_room_at_max_outbound() {
    assert!(!stale_follow_needs_room(0, 16));
    assert!(!stale_follow_needs_room(15, 16));
    assert!(stale_follow_needs_room(16, 16));
    assert!(stale_follow_needs_room(31, 16));
    assert!(stale_follow_needs_room(1, 1));
    assert!(!stale_follow_needs_room(0, 1));
}

/// `--proxy` or `--onion` with `--trust-peer` must not turn on isolated
/// broadcast. This node's own txs go out on the standing session.
#[test]
fn review_trust_proxy_uses_standing_relay() {
    let mut cfg = NodeConfig::default();
    assert!(!proxy_or_onion_without_trust(&cfg));
    let socks: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    cfg.listen.proxy = Some(socks);
    assert!(proxy_or_onion_without_trust(&cfg));
    cfg.listen.proxy = None;
    cfg.listen.onion = Some(socks);
    assert!(proxy_or_onion_without_trust(&cfg));
    cfg.trust_peer = Some(rbitcoin_net::NetAddr::Ip("192.0.2.1:8333".parse().unwrap()));
    assert!(!proxy_or_onion_without_trust(&cfg));
    cfg.listen.onion = None;
    cfg.listen.proxy = Some(socks);
    assert!(!proxy_or_onion_without_trust(&cfg));
}

#[test]
fn trust_peer_dials_only_that_peer() {
    use rbitcoin_node::cli::{operator_config_from_args, OperatorArgs};
    use rbitcoin_node::config::P2pListen;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-trust-dial-{n}"));
    let addr = "192.0.2.1:8333";
    let cfg = match operator_config_from_args(
        [
            "rbitcoin-node",
            "--datadir",
            dir.to_str().unwrap(),
            "--network",
            "regtest",
            "--trust-peer",
            addr,
        ],
        &NodeEnv::default(),
    ) {
        Ok(OperatorArgs::Ready { config, .. }) => config,
        other => panic!("expected config, got {other:?}"),
    };
    assert!(cfg.trust_peer_set());
    assert!(matches!(cfg.listen.p2p, P2pListen::Off));
    assert_eq!(cfg.listen.max_inbound, 0);
    assert!(!cfg.listen.use_seeds);
    assert!(!should_resolve_default_seeds(&cfg));
    assert!(!seednodes_allowed(&cfg.listen));
    let mut book = AddrMan::new();
    book.add("198.51.100.9:8333".parse().unwrap());
    book.add(addr.parse().unwrap());
    let got = outbound_dial_targets(true, &cfg.listen.connect, &book, 8, &[]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].to_string(), addr);
    let unresolved = outbound_dial_targets(true, &[], &book, 8, &[]);
    assert!(
        unresolved.is_empty(),
        "unresolved trust-peer must not dial the peers file"
    );
    let open = follow_dial_targets(&[], &book, 8, &[]);
    assert!(
        !open.is_empty(),
        "the peers file is still a dial target when trust-peer is off"
    );
    let shared = std::sync::Arc::new(std::sync::Mutex::new(book));
    let pinned = rbitcoin_net::NetAddr::Ip(addr.parse().unwrap());
    let trust_book = rbitcoin_ibd::PeerBookSession::new(ibd_shared_peers(true, &shared), &[pinned]);
    let trust_cands = trust_book
        .book()
        .take_dial_candidates_net(8, &Default::default(), &[]);
    assert_eq!(trust_cands, vec![pinned], "{trust_cands:?}");
    let open_book = rbitcoin_ibd::PeerBookSession::new(ibd_shared_peers(false, &shared), &[]);
    let open_cands = open_book
        .book()
        .take_dial_candidates_net(8, &Default::default(), &[]);
    assert!(
        open_cands
            .iter()
            .any(|a| a.to_string() == "198.51.100.9:8333"),
        "flag off still dials the peers file: {open_cands:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn follow_dial_targets_connect_bypasses_diversity() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let mut am = AddrMan::new();
    am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333));
    am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 0, 1)), 8333));
    let connect = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        8333,
    ))];
    let occupied = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)),
        8333,
    ))];
    let want = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        8333,
    ))];
    assert_eq!(follow_dial_targets(&connect, &am, 8, &occupied), want);
    // Core reports `-connect` peers as `manual`; addrman picks are full relay.
    assert_eq!(follow_dial_type(&connect), PeerConnType::Manual);
    assert_eq!(follow_dial_type(&[]), PeerConnType::OutboundFullRelay);
}

#[test]
fn seednode_window_ignores_the_catchup_dial() {
    let clock = rbitcoin_consensus::clock::NodeClock::new();
    clock.set_mock(1_700_000_000);
    clock.note_connection_attempt();
    let catch_up = clock.connection_attempt_at();
    clock.set_mock((catch_up + 11) as i64);
    assert!(
        seednode_delay_elapsed(catch_up, clock.now_secs()),
        "a catch-up dial is already 11s old when follow starts"
    );
    arm_seednode_follow_wait(&clock, 1);
    assert!(
        seednode_window_start(clock.connection_attempt_at()).is_none(),
        "arming the follow wait drops the catch-up sample"
    );
    clock.note_connection_attempt();
    let follow = seednode_window_start(clock.connection_attempt_at()).expect("follow dial");
    assert_ne!(follow, catch_up);
    assert!(
        !seednode_delay_elapsed(follow, clock.now_secs()),
        "the follow dial is the new sample, so the old jump must not add seeds"
    );
    clock.set_mock((follow + 11) as i64);
    assert_eq!(
        seednode_window_start(clock.connection_attempt_at()),
        Some(follow),
        "setmocktime during the follow hold must not move that sample"
    );
    assert!(seednode_delay_elapsed(follow, clock.now_secs()));
}

#[test]
fn seednode_window_opens_at_arm_when_follow_queues_no_dial() {
    let clock = rbitcoin_consensus::clock::NodeClock::new();
    clock.set_mock(1_700_000_000);
    clock.note_connection_attempt();
    let catch_up = clock.connection_attempt_at();
    clock.set_mock((catch_up + 11) as i64);
    assert!(
        seednode_delay_elapsed(catch_up, clock.now_secs()),
        "the catch-up dial is already old when follow has nothing to dial"
    );
    arm_seednode_follow_wait(&clock, 0);
    let started = seednode_window_start(clock.connection_attempt_at())
        .expect("no follow dial opens the window at arm time");
    assert_ne!(started, catch_up);
    assert_eq!(started, clock.now_secs());
    assert!(
        !seednode_delay_elapsed(started, clock.now_secs()),
        "arm time itself is not already 10s old"
    );
    clock.set_mock((started + 11) as i64);
    assert_eq!(
        seednode_window_start(clock.connection_attempt_at()),
        Some(started),
        "setmocktime must not move the arm sample"
    );
    assert!(seednode_delay_elapsed(started, clock.now_secs()));
}

#[test]
fn seednode_window_stays_on_the_dial_when_mock_jumps() {
    let clock = rbitcoin_consensus::clock::NodeClock::new();
    clock.set_mock(1_700_000_000);
    assert!(
        seednode_window_start(clock.connection_attempt_at()).is_none(),
        "no dial yet"
    );
    clock.note_connection_attempt();
    let started = seednode_window_start(clock.connection_attempt_at()).expect("dial sample");
    clock.set_mock((started + 11) as i64);
    assert_eq!(
        seednode_window_start(clock.connection_attempt_at()),
        Some(started),
        "setmocktime must not move the dial sample"
    );
    assert!(
        seednode_delay_elapsed(started, clock.now_secs()),
        "setmocktime(now+11) after the dial opens the seednode window"
    );
    assert!(
        !seednode_delay_elapsed(clock.now_secs(), clock.now_secs()),
        "sampling the clock after the jump starts the wait at the mock"
    );
}

#[test]
fn seednode_delay_starts_at_the_first_dial() {
    assert!(
        !seednode_delay_elapsed(0, 1_700_000_011),
        "no dial yet, so a clock jump must not add the seednode"
    );
    let started = 1_700_000_000u64;
    assert!(
        !seednode_delay_elapsed(started, started),
        "the dial itself must not add the seednode"
    );
    assert!(
        !seednode_delay_elapsed(started, started + 9),
        "nine seconds is still inside the addrman window"
    );
    assert!(
        seednode_delay_elapsed(started, started + 11),
        "setmocktime(now+11) after the dial must open the window"
    );
}

#[test]
fn seednodes_are_off_under_connect() {
    let mut listen = NodeConfig::default().listen;
    assert!(!seednodes_allowed(&listen), "no seednodes");
    listen.seednodes = vec!["127.0.0.1:18444".into()];
    assert!(seednodes_allowed(&listen));
    listen.connect = vec![rbitcoin_net::NetAddr::Ip(
        "127.0.0.1:18445".parse().unwrap(),
    )];
    assert!(
        !seednodes_allowed(&listen),
        "Core skips seednodes under -connect"
    );
    listen.connect.clear();
    listen.connect_dns = vec!["localhost:18445".into()];
    assert!(!seednodes_allowed(&listen), "a --connect hostname pins too");
}

/// An empty address book dials the operator onion seednode through SOCKS.
/// The 10s wait before a populated book falls back is
/// [`seednode_delay_elapsed`], not a second live run.
#[tokio::test]
async fn onion_seednode_reaches_socks_from_operator_config() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = rbitcoin_store::testutil::TempDir::new().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let onion = "vqfiycyhxoh44hciaznjyeasgevc7n3ht6sbo5ifbdazxyflq6xoidid.onion";
    let mut cfg = tiny_regtest(dir.path());
    cfg.apply_kv("milestone", "0").unwrap();
    cfg.apply_kv("listen", "0").unwrap();
    cfg.apply_kv("max_inbound", "0").unwrap();
    cfg.apply_kv("only_net", "onion").unwrap();
    cfg.apply_kv("onion", &proxy.to_string()).unwrap();
    cfg.apply_kv("seed_node", &format!("{onion}:8333")).unwrap();
    cfg.listen.use_seeds = false;
    cfg.max_run_secs = Some(2);
    cfg.validate().unwrap();

    let capture = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 2];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; greeting[1] as usize];
        socket.read_exact(&mut methods).await.unwrap();
        assert!(
            methods.contains(&2),
            "addrfetch uses isolated SOCKS credentials"
        );
        socket.write_all(&[5, 2]).await.unwrap();
        assert_eq!(socket.read_u8().await.unwrap(), 1);
        let username_len = socket.read_u8().await.unwrap();
        let mut username = vec![0; username_len as usize];
        socket.read_exact(&mut username).await.unwrap();
        let password_len = socket.read_u8().await.unwrap();
        let mut password = vec![0; password_len as usize];
        socket.read_exact(&mut password).await.unwrap();
        assert!(!username.is_empty() && !password.is_empty());
        socket.write_all(&[1, 0]).await.unwrap();
        let mut header = [0; 5];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut host = vec![0; header[4] as usize];
        socket.read_exact(&mut host).await.unwrap();
        let port = socket.read_u16().await.unwrap();
        socket
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert_eq!(port, 8333, "empty book dials the operator seednode");
        (String::from_utf8(host).unwrap(), port)
    });
    tokio::time::timeout(Duration::from_secs(45), run_p2p(cfg))
        .await
        .expect("seednode run must stop")
        .unwrap();
    let captured = tokio::time::timeout(Duration::from_secs(1), capture).await;
    assert_eq!(
        captured
            .expect("onion seednode must reach SOCKS CONNECT")
            .unwrap(),
        (onion.to_string(), 8333)
    );
}

#[test]
fn follow_dial_targets_keeps_i2p_connect() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let mut am = AddrMan::new();
    am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333));
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [7u8; 32],
        port: 8333,
    };
    let connect = vec![i2p];
    let got = follow_dial_targets(&connect, &am, 8, &[]);
    assert_eq!(got, vec![i2p]);
}

#[test]
fn follow_dial_targets_skips_occupied_group() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let mut am = AddrMan::new();
    let same = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 0, 1)), 8333);
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 3, 0, 1)), 8333);
    am.add(same);
    am.add(other);
    let occupied = vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(1, 2, 0, 9)),
        8333,
    ))];
    let got = follow_dial_targets(&[], &am, 1, &occupied);
    assert_eq!(got, vec![rbitcoin_net::NetAddr::Ip(other)]);
}

#[test]
fn follow_dial_targets_picks_addrman_onion() {
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.set_only_net(vec![rbitcoin_net::OnlyNet::Onion]);
    am.add_addr(onion);
    assert_eq!(follow_dial_targets(&[], &am, 1, &[]), vec![onion]);
    assert!(
        follow_dial_targets(&[], &am, 1, &[onion]).is_empty(),
        "live onion net must not be re-dialed via 0.0.0.0 hint"
    );
}

#[test]
fn tip_follow_checks_stale_on_perf_and_rpc_stop() {
    assert!(
        tip_follow_checks_stale(TipFollowWakeKind::Perf),
        "5s tip:perf tick must still consider a stale extra outbound"
    );
    assert!(
        tip_follow_checks_stale(TipFollowWakeKind::RpcStop),
        "RPC-stop tick must still consider a stale extra outbound"
    );
    assert!(tip_follow_checks_stale(TipFollowWakeKind::Poll));
    assert!(tip_follow_checks_stale(TipFollowWakeKind::TipSame));
    assert!(!tip_follow_checks_stale(TipFollowWakeKind::TipChanged));
    assert!(!tip_follow_checks_stale(TipFollowWakeKind::Refill));
    assert!(!tip_follow_checks_stale(TipFollowWakeKind::Stop));
}

#[test]
fn parse_blockmintxfee_btc_to_sat() {
    assert_eq!(parse_btc_to_sat("0.00000001"), Ok(1));
    assert_eq!(parse_btc_to_sat("0"), Ok(0));
    assert_eq!(parse_btc_to_sat("0.025"), Ok(2_500_000));
    assert_eq!(parse_btc_to_sat("0.00000005"), Ok(5));
    assert_eq!(parse_btc_to_sat("-0.0001"), Err("must be non-negative"));
    assert_eq!(parse_btc_to_sat("nope"), Err("invalid"));
}

/// Persistent stale interval must complete even when a faster perf tick
/// is in the same biased `select!` (the old one-shot sleep never did).
#[tokio::test]
async fn stale_interval_fires_alongside_faster_perf_tick() {
    let mut perf = tokio::time::interval(Duration::from_millis(15));
    perf.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    perf.tick().await;
    let mut stale = tokio::time::interval(Duration::from_millis(50));
    stale.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    stale.tick().await;
    let mut refill = tokio::time::interval(Duration::from_secs(30));
    refill.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refill.tick().await;
    let learned = tokio::sync::Notify::new();
    let (_tx, mut tip_rx) = broadcast::channel::<TipEvent>(8);
    let start = Instant::now();
    let mut saw_poll = false;
    while start.elapsed() < Duration::from_millis(200) {
        let w = tokio::time::timeout(
            Duration::from_millis(250),
            tip_follow_next_wake(
                std::future::pending(),
                None,
                &mut perf,
                &mut tip_rx,
                &mut stale,
                &mut refill,
                &learned,
                None,
            ),
        )
        .await
        .expect("supervisor wake");
        if matches!(w, TipFollowWake::Poll) {
            saw_poll = true;
            break;
        }
    }
    assert!(
        saw_poll,
        "stale interval must produce Poll while perf ticks every 15ms"
    );
}

#[test]
fn catch_up_ok_genesis_zero_accepts_is_incomplete() {
    assert_eq!(catch_up_after_ok(0, 0, false), CatchUp::Incomplete);
    assert_eq!(catch_up_after_ok(3, 3, true), CatchUp::Incomplete);
}

#[test]
fn catch_up_ok_with_blocks_is_complete() {
    assert_eq!(
        catch_up_after_ok(3, 3, false),
        CatchUp::Complete {
            dial_failed_all: false
        }
    );
    assert_eq!(
        catch_up_after_ok(0, 1, false),
        CatchUp::Complete {
            dial_failed_all: false
        }
    );
    assert!(CatchUp::complete().is_complete());
    assert!(!CatchUp::complete().dial_failed_all());
    assert!(!CatchUp::Incomplete.is_complete());
}

#[test]
fn empty_targets_stay_open_until_a_dialable_address_exists() {
    assert!(catch_up_without_targets(false).is_complete());
    assert!(
        !catch_up_without_targets(true).is_complete(),
        "a swept or seed-pending book is not caught up"
    );
}

#[test]
fn catch_up_err_with_tip_indexes_dials_failed() {
    assert_eq!(
        catch_up_after_err(10, true, false),
        CatchUp::Complete {
            dial_failed_all: true
        }
    );
    assert!(CatchUp::complete_dial_failed().dial_failed_all());
    assert_eq!(catch_up_after_err(10, false, false), CatchUp::Incomplete);
    assert_eq!(catch_up_after_err(0, true, false), CatchUp::Incomplete);
    assert_eq!(catch_up_after_err(10, true, true), CatchUp::Incomplete);
}

#[test]
fn connect_genesis_incomplete_enters_tip_follow() {
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, true, false, 0),
        CatchUp::complete_dial_failed()
    );
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, false, false, 0),
        CatchUp::Incomplete
    );
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, true, true, 0),
        CatchUp::Incomplete
    );
    assert!(catch_up_with_connect(CatchUp::complete(), true, false, 0).is_complete());
}

#[test]
fn connect_nongenesis_incomplete_stays_in_ibd() {
    assert_eq!(
        catch_up_with_connect(CatchUp::Incomplete, true, false, 50),
        CatchUp::Incomplete
    );
}

/// Catch-up can leave a full-relay peer connected. When indexing finishes
/// on a tip that is already fresh, that peer must get one fee filter as
/// relay turns on, and fee-history preload is taken once. A second pass,
/// `-blocksonly`, and a stale tip send nothing.
#[tokio::test]
async fn indexing_finished_sends_feefilter_once_when_the_tip_is_fresh() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::{Dialer, MempoolHub, P2PNode, PeerConnType, PeerOut};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    struct Edge {
        node: P2PNode,
        mempool: Arc<MempoolHub>,
        config: NodeConfig,
        rx: mpsc::UnboundedReceiver<PeerOut>,
        floor: i64,
    }

    async fn world(blocksonly: bool, fresh: bool) -> Edge {
        let dir = scratch_dir(if fresh && !blocksonly {
            "index-fee"
        } else if blocksonly {
            "index-fee-bo"
        } else {
            "index-fee-stale"
        });
        let mut config = tiny_regtest(&dir);
        config.mempool.blocksonly = blocksonly;
        let node = P2PNode::start_outbound_only(
            Query::open_or_create_tiny(dir.join("store")).unwrap(),
            ChainParams::regtest(),
            Milestone::NONE,
            "/rbitcoin:test/".into(),
            0,
            Dialer::Direct,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        if fresh {
            node.hub.finished_ibd.store(true, Ordering::Release);
        }
        let mempool = MempoolHub::open(dir.join("mempool"), Arc::clone(&node.query)).unwrap();
        assert!(
            node.hub.attach_mempool(Arc::clone(&mempool)).is_ok(),
            "mempool attaches once"
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let peer = node
            .peers
            .register(addr, addr, &ver, false, PeerConnType::OutboundFullRelay);
        let (tx, rx) = mpsc::unbounded_channel();
        peer.attach_out(tx);
        let floor = node.hub.feefilter_sat_kvb() as i64;
        Edge {
            node,
            mempool,
            config,
            rx,
            floor,
        }
    }

    async fn run_edge(edge: &Edge) {
        sync_tx_relay(&edge.node, &edge.config, &edge.mempool)
            .await
            .unwrap();
    }

    let mut fresh = world(false, true).await;
    assert!(
        !fresh.node.hub.in_ibd() && !fresh.mempool.relay_enabled(),
        "the tip is fresh and relay has not flipped"
    );
    run_edge(&fresh).await;
    match fresh.rx.try_recv() {
        Ok(PeerOut::Msg(NetworkMessage::FeeFilter(fee))) => {
            assert_eq!(fee, fresh.floor, "the filter is the post-IBD floor");
        }
        other => panic!("indexing finished must queue one feefilter, got {other:?}"),
    }
    assert!(fresh.rx.try_recv().is_err(), "one filter, not a burst");
    assert!(fresh.mempool.relay_enabled());
    assert!(
        !fresh.mempool.take_fee_backfill_due(),
        "preload is taken on that same edge"
    );
    run_edge(&fresh).await;
    assert!(
        fresh.rx.try_recv().is_err(),
        "a second pass does not send another filter"
    );
    assert!(!fresh.mempool.take_fee_backfill_due());
    fresh.node.shutdown().await;

    let mut blocks = world(true, true).await;
    run_edge(&blocks).await;
    assert!(blocks.rx.try_recv().is_err(), "-blocksonly sends no filter");
    assert!(!blocks.mempool.relay_enabled());
    blocks.node.shutdown().await;

    let mut stale = world(false, false).await;
    assert!(stale.node.hub.in_ibd(), "regtest genesis is still IBD");
    run_edge(&stale).await;
    assert!(stale.rx.try_recv().is_err(), "a stale tip sends no filter");
    assert!(!stale.mempool.relay_enabled());
    stale.node.shutdown().await;
}

/// A tip-mode accept owes fee-history preload. The default node has no RPC
/// server, and the tip-follow wake is what takes that bit.
#[tokio::test]
async fn tip_follow_wake_preloads_fees_without_rpc() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::{Dialer, MempoolHub, P2PNode};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let dir = scratch_dir("tip-follow-fee");
    let config = tiny_regtest(&dir);
    let node = P2PNode::start_outbound_only(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:test/".into(),
        0,
        Dialer::Direct,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    node.hub.finished_ibd.store(true, Ordering::Release);
    let mempool = MempoolHub::open(dir.join("mempool"), Arc::clone(&node.query)).unwrap();
    assert!(node.hub.attach_mempool(Arc::clone(&mempool)).is_ok());
    mempool.set_relay_enabled(true);
    assert!(mempool.relay_enabled());
    assert!(!node.hub.in_ibd());
    let stop = finish_tip_follow_wake(
        &node,
        &config,
        &mempool,
        None,
        &TipFollowWake::Perf,
        &Shutdown::new(),
    )
    .await
    .unwrap();
    assert!(!stop, "a perf wake keeps the loop running");
    assert!(
        !mempool.take_fee_backfill_due(),
        "a tip-follow wake with no RPC server still consumes fee preload"
    );
    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn relay_requires_min_chain_work_even_when_following() {
    assert!(!relay_while_following(false, false, false));
    assert!(relay_while_following(true, false, false));
    assert!(!relay_while_following(true, true, false));
    assert!(!relay_while_following(true, false, true));
    let mut cfg = NodeConfig::default();
    assert!(cfg.meets_minimum_chain_work([0; 32]));
    cfg.minimum_chain_work = Some([0xff; 32]);
    assert!(
        !cfg.meets_minimum_chain_work([0; 32]),
        "a non-genesis tip under --min-chain-work follows, but relay stays gated"
    );
}

#[test]
fn cjdns_listen_is_advertised_without_external_ip() {
    use std::net::{IpAddr, Ipv6Addr};
    let fc = Ipv6Addr::new(0xfc00, 1, 2, 3, 4, 5, 6, 7);
    let bind = SocketAddr::from((fc, 8333));
    let got = external_ips_with_cjdns_bind(&[], bind, true);
    assert_eq!(got, vec![IpAddr::V6(fc)]);
    assert!(
        external_ips_with_cjdns_bind(&[], bind, false).is_empty(),
        "fc00 stays unroutable until --cjdns-reachable"
    );
    let v4 = SocketAddr::from(([1, 2, 3, 4], 8333));
    assert!(external_ips_with_cjdns_bind(&[], v4, true).is_empty());
    let ula = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 8333));
    assert!(
        external_ips_with_cjdns_bind(&[], ula, true).is_empty(),
        "fd00::/8 is not CJDNS"
    );
    let dup = external_ips_with_cjdns_bind(&[IpAddr::V6(fc)], bind, true);
    assert_eq!(dup, vec![IpAddr::V6(fc)]);
}

#[test]
fn follow_connect_timeout_i2p_is_longer_than_clearnet() {
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 1,
    };
    let ip: rbitcoin_net::NetAddr = "127.0.0.1:1".parse().unwrap();
    assert_eq!(
        follow_connect_timeout(&Dialer::Direct, ip),
        Duration::from_secs(FOLLOW_CONNECT_SECS)
    );
    assert_eq!(
        follow_connect_timeout(&Dialer::Direct, i2p),
        Duration::from_secs(90)
    );
}

#[test]
fn startup_catch_up_waits_for_peers_only_when_a_give_up_would_exit() {
    assert_eq!(
        main_catch_up_peerless(false, None),
        rbitcoin_ibd::Peerless::Redial {
            cap: rbitcoin_ibd::PEERLESS_REDIAL_CAP
        },
        "a give-up with catch-up indexes would end the process"
    );
    assert_eq!(
        main_catch_up_peerless(true, None),
        rbitcoin_ibd::Peerless::GiveUp,
        "a give-up with tip indexes enters tip follow"
    );
    assert_eq!(
        main_catch_up_peerless(false, Some(0)),
        rbitcoin_ibd::Peerless::GiveUp,
        "a capped run returns to its caller"
    );
}

#[test]
fn follow_targets_refresh_after_catch_up_learns_peers() {
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let mut addrman = AddrMan::new();
    assert!(
        refresh_follow_targets(false, &[], &shared, &mut addrman, 2, &[]).is_empty(),
        "empty book has no follow targets"
    );
    shared
        .lock()
        .unwrap()
        .add_addr(rbitcoin_net::NetAddr::Ip("127.0.0.1:1".parse().unwrap()));
    assert_eq!(
        refresh_follow_targets(false, &[], &shared, &mut addrman, 2, &[]).len(),
        1,
        "tip follow must see a peer learned during catch-up"
    );
    assert!(
        refresh_follow_targets(true, &[], &shared, &mut addrman, 2, &[]).is_empty(),
        "trust-peer does not follow a peer the book learned"
    );
}

#[tokio::test]
async fn empty_book_waits_for_a_discovered_target() {
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let shutdown = Shutdown::new();
    let peers = Arc::new(rbitcoin_net::PeerHub::new());
    let parked = peers.dial_parked().notified();
    tokio::pin!(parked);
    let shared_task = Arc::clone(&shared);
    let shutdown_task = Arc::clone(&shutdown);
    let peers_task = Arc::clone(&peers);
    let task = tokio::spawn(async move {
        let mut book = AddrMan::new();
        wait_for_dialable_targets(
            &peers_task,
            &shared_task,
            &mut book,
            &[],
            2,
            &[],
            &shutdown_task,
            false,
            rbitcoin_primitives::Network::Regtest,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), parked)
        .await
        .expect("empty book parks before a discovered address");
    assert!(
        !task.is_finished(),
        "an empty book with discovery in flight must stay in catch-up"
    );
    let started = Instant::now();
    shared
        .lock()
        .unwrap()
        .add_addr(rbitcoin_net::NetAddr::Ip("127.0.0.1:1".parse().unwrap()));
    let found = tokio::time::timeout(Duration::from_millis(50), task)
        .await
        .expect("learned target wakes catch-up within 50ms")
        .expect("wait task");
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "join took {:?}",
        started.elapsed()
    );
    assert_eq!(found.expect("dial targets").len(), 1);

    let shutdown = Shutdown::new();
    shutdown.request();
    let peers = Arc::new(rbitcoin_net::PeerHub::new());
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let mut book = AddrMan::new();
    assert!(
        wait_for_dialable_targets(
            &peers,
            &shared,
            &mut book,
            &[],
            2,
            &[],
            &shutdown,
            false,
            rbitcoin_primitives::Network::Regtest,
        )
        .await
        .is_none(),
        "shutdown ends the empty-book wait"
    );
}

#[test]
fn custom_signet_does_not_use_default_signet_seeds() {
    let mut cfg = NodeConfig::default().with_network(rbitcoin_primitives::Network::Signet);
    assert!(should_resolve_default_seeds(&cfg));
    cfg.signet_challenge = Some(bitcoin::ScriptBuf::from_bytes(vec![0x51]));
    assert!(!should_resolve_default_seeds(&cfg));
}

#[test]
fn dns_seeds_not_resolved_locally_when_proxy() {
    let mut cfg = NodeConfig::default();
    assert!(should_resolve_default_seeds(&cfg));
    cfg.listen.proxy = Some("127.0.0.1:9050".parse().unwrap());
    assert!(
        !should_resolve_default_seeds(&cfg),
        "proxy path must not ToSocketAddrs DNS/fixed seeds"
    );
}

#[test]
fn proxy_seed_bootstrap_queues_domain_addrfetch() {
    let peers = rbitcoin_net::PeerHub::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<rbitcoin_net::DialRequest>();
    peers.set_dialer(tx);
    let n = queue_proxy_seed_addrfetch(&peers, rbitcoin_primitives::Network::Signet);
    assert_eq!(n, 2, "signet has two default DNS seeds");
    for want in [
        "seed.signet.bitcoin.sprovoost.nl.",
        "seed.signet.achownodes.xyz.",
    ] {
        let req = rx.try_recv().expect("queued dial request");
        assert_eq!(req.typ, PeerConnType::AddrFetch);
        match req.target {
            rbitcoin_net::DialTarget::Domain { host, port } => {
                assert_eq!(host, want);
                assert_eq!(port, 38333);
            }
            other => panic!("expected domain target, got {other:?}"),
        }
    }
    assert!(rx.try_recv().is_err(), "no third seed dial");
}

#[test]
fn shutdown_flag_and_node_handle_smoke() {
    let sd = Shutdown::new();
    assert!(!sd.requested());
    sd.request();
    assert!(sd.requested());
    assert!(
        sd.result().is_ok(),
        "SIGTERM and RPC stop stay a clean exit"
    );
    sd.request();
    assert!(sd.requested());
    let failed = Shutdown::new();
    failed.fail(rbitcoin_node::NodeError::Init("first".into()));
    failed.fail(rbitcoin_node::NodeError::Init("second".into()));
    assert!(failed.requested());
    assert_eq!(failed.result().unwrap_err().to_string(), "Error: first");

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-run-node-{nanos}"));
    let cfg = tiny_regtest(&dir);
    let handle = run_node(cfg).expect("run_node");
    assert_eq!(handle.network_name(), "regtest");
    assert_eq!(
        handle.query.store().headers.head_target_slots(),
        64,
        "tiny_regtest must create Tiny header heads"
    );
    assert!(handle.mempool.is_none());
    let _ = format!("{:?}", handle);
    handle.shutdown().expect("shutdown flush");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cancelled_completes_after_request() {
    let sd = Shutdown::new();
    // Already-requested path returns immediately.
    sd.request();
    sd.cancelled().await;

    let sd2 = Shutdown::new();
    let s2 = Arc::clone(&sd2);
    let j = tokio::spawn(async move {
        s2.cancelled().await;
    });
    // Give the task a chance to park on notify.
    tokio::task::yield_now().await;
    sd2.request();
    j.await.unwrap();
}

/// The `IbdConfig` literal in `run_ibd_or_skip` is not built by the config
/// journey, so this drives `run_p2p`. A refused connect must flush a fail
/// mark into the saved book, and the SOCKS proxy must be the socket dialed.
#[tokio::test]
async fn run_p2p_refused_connect_flushes_book_and_dials_proxy() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-run-p2p-proxy-{nanos}"));
    let proxy_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = proxy_l.local_addr().unwrap();
    let target_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connect = target_l.local_addr().unwrap();
    let proxy_hit = Arc::new(AtomicBool::new(false));
    let target_hit = Arc::new(AtomicBool::new(false));
    let proxy_flag = Arc::clone(&proxy_hit);
    let target_flag = Arc::clone(&target_hit);
    std::thread::spawn(move || {
        while let Ok((mut sock, _)) = proxy_l.accept() {
            proxy_flag.store(true, Ordering::SeqCst);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
            let mut buf = [0u8; 16];
            let _ = sock.read(&mut buf);
            // No acceptable SOCKS method: the dial fails before CONNECT.
            let _ = sock.write_all(&[0x05, 0xFF]);
        }
    });
    std::thread::spawn(move || {
        while target_l.accept().is_ok() {
            target_flag.store(true, Ordering::SeqCst);
        }
    });

    let mut cfg = tiny_regtest(&dir).with_p2p_listen("127.0.0.1:0".parse().unwrap());
    cfg.listen.use_seeds = false;
    cfg.listen.connect = vec![rbitcoin_net::NetAddr::from_socket(connect)];
    cfg.listen.proxy = Some(proxy);
    cfg.max_run_secs = Some(0);
    let result = tokio::time::timeout(Duration::from_secs(20), run_p2p(cfg)).await;
    assert!(result.is_ok(), "run_p2p timed out");
    let _ = result.unwrap();

    assert!(
        proxy_hit.load(Ordering::SeqCst),
        "IBD must dial the configured SOCKS proxy"
    );
    assert!(
        !target_hit.load(Ordering::SeqCst),
        "SOCKS dial must not open a direct TCP connection to the target"
    );
    let peers_path = dir.join("peers");
    let text = std::fs::read_to_string(&peers_path).expect("peers saved");
    let row = text
        .lines()
        .find(|line| line.starts_with(&format!("{connect} ")))
        .unwrap_or_else(|| {
            panic!("IBD must flush the dial failure into the saved peer book\n{text}")
        });
    let flags = row
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        .unwrap_or(0);
    assert!(
        flags & rbitcoin_net::PeerFlags::FAILED_LAST_CONNECT != 0,
        "IBD must flush the dial failure into the saved peer book, row {row}"
    );
    let book = AddrMan::load(&peers_path).expect("peers saved");
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(connect))
            .is_none(),
        "loopback is not restored from the peers file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn node_handle_shutdown_with_mempool() {
    use rbitcoin_net::MempoolHub;
    use std::sync::Arc;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-handle-mp-{nanos}"));
    let cfg = tiny_regtest(&dir);
    let mut handle = run_node(cfg).expect("run_node");
    // Dual-open same store for MempoolHub's Arc<Query> (flush only).
    // Same layout as run_node — Tiny here, Mainnet would mismatch.
    let q = Arc::new(Query::open_or_create_layout(handle.config.store_layout()).unwrap());
    let mp = MempoolHub::open(handle.config.mempool_path(), q).expect("mempool");
    handle.mempool = Some(mp);
    let _ = format!("{:?}", handle);
    handle.shutdown().expect("flush query+mempool");
    let _ = std::fs::remove_dir_all(&dir);
}

fn scratch_dir(label: &str) -> std::path::PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-{label}-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn startup_sets_datadir_hdd_on_the_store() {
    let dir = scratch_dir("datadir-hdd");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    assert!(!q.store().datadir_hdd());
    let mut cfg = NodeConfig::default();
    cfg.datadir_hdd = true;
    apply_startup_index_mode(&q, &cfg, 0).unwrap();
    assert!(q.store().datadir_hdd());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn startup_sets_sh_force_rebuild_on_the_query() {
    let dir = scratch_dir("sh-force-rebuild");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    assert!(!q.sh_force_rebuild());
    let mut cfg = NodeConfig::default();
    cfg.sh_force_rebuild = true;
    apply_startup_index_mode(&q, &cfg, 0).unwrap();
    assert!(q.sh_force_rebuild());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pack-marked head whose inclusion floor is behind the tip must not open
/// Electrum. Tip follow still starts so write-behind can catch up.
#[test]
fn enter_tip_mode_does_not_ready_electrum_when_inclusion_lags() {
    let dir = scratch_dir("tip-gate");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let bump = q.store().scripthash.alloc_bump();
    let session = q.store().scripthash.pack_shard_session(0).unwrap();
    let pack = session.finish_pack().unwrap();
    assert_eq!(pack.bump, bump);
    q.store().scripthash.publish_packed_shard(0, pack).unwrap();
    assert!(q.store().scripthash.has_durable_index());
    assert!(q.sh_use_writebehind());
    assert!(
        !q.sh_is_tip_ready(),
        "empty tip is not an inclusion-complete scripthash head"
    );
    let gates = enter_tip_mode(&q, None, true);
    assert!(gates.tip_follow_ready);
    assert!(
        !gates.sh_tip_ready,
        "lagging inclusion must not start Electrum"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancel before any extract file exists must not tell the operator to
/// resume from `scripthash.cold_progress`.
#[test]
fn enter_tip_mode_cancel_does_not_name_missing_cold_progress() {
    let dir = scratch_dir("tip-cancel");
    let q = Query::open_or_create_tiny(&dir).unwrap();
    assert!(!q.store().path().join("scripthash.cold_progress").is_file());
    assert!(!q.store().path().join("scripthash.unsorted").is_dir());
    let cancel = Arc::new(AtomicBool::new(true));
    rbitcoin_log::capture_logs(true);
    let gates = enter_tip_mode(&q, Some(cancel), true);
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(gates.tip_follow_ready);
    assert!(!gates.sh_tip_ready);
    let joined = lines
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !joined.contains("scripthash.cold_progress"),
        "cancel warn named a resume file that is not on disk:\n{joined}"
    );
    assert!(
        joined.contains("cancelled before a durable scripthash extract"),
        "cancel warn should name the phase that actually exists:\n{joined}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Materialize holds the worker for the whole extract. A reactor thread
/// must not be that worker.
#[test]
fn enter_tip_mode_refuses_a_reactor_worker() {
    let dir = scratch_dir("tip-reactor");
    let query = Arc::new(Query::open_or_create_tiny(&dir).unwrap());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    let on_worker = Arc::clone(&query);
    let panicked = rt.block_on(async move {
        tokio::spawn(async move {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                enter_tip_mode(&on_worker, None, false);
            }))
            .is_err()
        })
        .await
        .expect("reactor task")
    });
    assert!(panicked, "enter_tip_mode must not run on a tokio-rt-worker");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same call is the blocking-pool job `run_p2p` uses after catch-up.
#[test]
fn enter_tip_mode_runs_in_a_blocking_region() {
    let dir = scratch_dir("tip-blocking");
    let query = Arc::new(Query::open_or_create_tiny(&dir).unwrap());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    let on_pool = Arc::clone(&query);
    rt.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let _region = rbitcoin_net::BlockingRegion::enter();
            enter_tip_mode(&on_pool, None, false);
        })
        .await
        .expect("blocking tip entry")
    });
    assert!(!query.enqueues_sh_writebehind());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Direct catch-up, a failed materialize, and `--sh-index` off do not start
/// the appender. A durable Tip head starts one `rbtc-sh-wb`. A second start
/// does not spawn another.
#[test]
fn sh_writebehind_starts_only_after_tip_entry() {
    let dir = scratch_dir("sh-wb-gate");
    let query = Arc::new(Query::open_or_create_tiny(&dir).unwrap());
    query.enter_direct_index_mode_sh(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let mut slot = None;
    ensure_sh_writebehind(&mut slot, Arc::clone(&query), Arc::clone(&stop), || {});
    assert!(slot.is_none(), "direct catch-up does not start rbtc-sh-wb");

    let cancel = Arc::new(AtomicBool::new(true));
    let gates = enter_tip_mode(&query, Some(cancel), true);
    assert!(gates.tip_follow_ready);
    assert!(!gates.sh_tip_ready);
    assert!(query.index_mode().unwrap().is_direct());
    ensure_sh_writebehind(&mut slot, Arc::clone(&query), Arc::clone(&stop), || {});
    assert!(
        slot.is_none(),
        "cancelled materialize stays Direct and does not start rbtc-sh-wb"
    );

    let gates = enter_tip_mode(&query, None, false);
    assert!(gates.sh_tip_ready);
    ensure_sh_writebehind(&mut slot, Arc::clone(&query), Arc::clone(&stop), || {});
    assert!(slot.is_none(), "shindex off does not start rbtc-sh-wb");

    query.set_sh_index_enabled(true);
    query.enter_tip_index_mode();
    ensure_sh_writebehind(&mut slot, Arc::clone(&query), Arc::clone(&stop), || {});
    let first = slot.as_ref().expect("durable tip").thread().id();
    ensure_sh_writebehind(&mut slot, Arc::clone(&query), Arc::clone(&stop), || {});
    assert_eq!(
        slot.as_ref().expect("same appender").thread().id(),
        first,
        "a second start must not replace rbtc-sh-wb"
    );
    #[cfg(target_os = "linux")]
    {
        let tid = slot
            .as_ref()
            .expect("durable tip")
            .wait_published(Duration::from_secs(1))
            .expect("rbtc-sh-wb published its tid");
        let comm =
            std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
        assert_eq!(comm.trim_end_matches('\n'), "rbtc-sh-wb");
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    slot.take().expect("rbtc-sh-wb").join().expect("rbtc-sh-wb");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn max_run_deadline_wakes_without_the_perf_tick() {
    let mut perf = tokio::time::interval(Duration::from_secs(30));
    perf.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    perf.tick().await;
    let mut stale = tokio::time::interval(Duration::from_secs(30));
    stale.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    stale.tick().await;
    let mut refill = tokio::time::interval(Duration::from_secs(30));
    refill.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refill.tick().await;
    let learned = tokio::sync::Notify::new();
    let (_tx, mut tip_rx) = broadcast::channel::<TipEvent>(8);
    let start = Instant::now();
    let wake = tokio::time::timeout(
        Duration::from_millis(500),
        tip_follow_next_wake(
            std::future::pending(),
            None,
            &mut perf,
            &mut tip_rx,
            &mut stale,
            &mut refill,
            &learned,
            Some(Instant::now() + Duration::from_millis(40)),
        ),
    )
    .await
    .expect("deadline must wake before the perf tick");
    assert!(matches!(wake, TipFollowWake::Stop));
    assert!(start.elapsed() < Duration::from_millis(200));
}

/// A fresh `--proxy` datadir has no targets until a seed's `getaddr`
/// reply is learned. The wait re-queues the seeds while no addr-fetch
/// session is live, ignores a book filled only by a self-announce, and
/// ends on that reply, shutdown, or its deadline.
///
/// The clock is paused. Polls still happen before the 400 ms deadline, so
/// a self-announce cannot pass as a reply, and that wait is not wall time.
#[tokio::test(start_paused = true)]
async fn proxy_seed_wait_ends_on_a_learned_reply_shutdown_or_deadline() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let peers = rbitcoin_net::PeerHub::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<rbitcoin_net::DialRequest>();
    peers.set_dialer(tx);
    let signet = rbitcoin_primitives::Network::Signet;
    let shared = Arc::new(std::sync::Mutex::new(AddrMan::new()));
    let announced: rbitcoin_net::NetAddr = "1.2.3.4:38333".parse().unwrap();
    shared.lock().unwrap().add_addr(announced);
    let replies = Arc::new(AtomicU64::new(0));
    let sd = Shutdown::new();
    let short = Duration::from_millis(50);

    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 38333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::Address::new(&at, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::Address::new(&at, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/seed:0/".into(),
        start_height: 0,
        relay: true,
    };
    let answering = peers.register(at, at, &ver, false, PeerConnType::AddrFetch);
    let counted = Arc::clone(&replies);
    let timed_out = await_proxy_seed_book(
        &peers,
        signet,
        &shared,
        &sd,
        move || counted.load(Ordering::SeqCst),
        short,
        Duration::from_millis(400),
    )
    .await;
    assert!(
        timed_out.is_none(),
        "a self-announce alone is not the reply"
    );
    assert!(
        rx.try_recv().is_err(),
        "a live addr-fetch session is not re-queued"
    );
    peers.unregister(answering.id);

    let seed = {
        let (shared, replies) = (Arc::clone(&shared), Arc::clone(&replies));
        tokio::spawn(async move {
            let req = rx.recv().await.expect("seed addr-fetch re-queued");
            assert_eq!(req.typ, PeerConnType::AddrFetch);
            shared
                .lock()
                .unwrap()
                .add_addr("5.6.7.8:38333".parse().unwrap());
            replies.fetch_add(1, Ordering::SeqCst);
        })
    };
    let counted = Arc::clone(&replies);
    let book = tokio::time::timeout(
        Duration::from_secs(5),
        await_proxy_seed_book(
            &peers,
            signet,
            &shared,
            &sd,
            move || counted.load(Ordering::SeqCst),
            short,
            Duration::from_secs(60),
        ),
    )
    .await
    .expect("the wait ends once a reply is learned")
    .expect("no shutdown and no deadline");
    seed.await.unwrap();
    assert_eq!(book.len(), 2);

    sd.request();
    let counted = Arc::clone(&replies);
    let book = await_proxy_seed_book(
        &peers,
        signet,
        &shared,
        &sd,
        move || counted.load(Ordering::SeqCst),
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .await;
    assert!(book.is_none(), "shutdown ends the wait with no book");
}

/// `--esplora-max-inflight` reaches the listener: with a limit of one, a
/// request whose body never arrives makes the next request wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_esplora_applies_max_inflight() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_esplora::server::EsploraListen;
    use rbitcoin_net::{ChainHub, MempoolHub};
    use rbitcoin_primitives::Network;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let dir = scratch_dir("esplora-max-inflight");
    let hub = Arc::new(ChainHub::new(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
    ));
    let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&hub.query)).unwrap();
    let shutdown = Shutdown::new();
    let handles = start_esplora_if_ready(
        true,
        Some(EsploraListen::Tcp("127.0.0.1:0".parse().unwrap())),
        Network::Regtest,
        None,
        1,
        &shutdown,
        Arc::clone(&hub),
        &mp,
    )
    .await
    .unwrap();
    let addr = handles[0].local_addr;
    let admit = Arc::clone(&handles[0].admit);

    let get = |addr| async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /blocks/tip/height HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        out
    };
    let mut stall = TcpStream::connect(addr).await.unwrap();
    stall
        .write_all(b"POST /tx HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\n")
        .await
        .unwrap();
    // The stall may not hold the slot yet. Wait until this GET is counted
    // as waiting, and retry if it was served before the slot filled.
    let mut waiting = None;
    for _ in 0..20 {
        let before = admit.waiting();
        let g = tokio::spawn(get(addr));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let notified = admit.notified();
            if !g.is_finished() && admit.waiting() > before {
                waiting = Some(g);
                break;
            }
            if g.is_finished() {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "a limit of one did not queue the request");
            if tokio::time::timeout(left, notified).await.is_err() {
                panic!("a limit of one did not queue the request");
            }
        }
        if waiting.is_some() {
            break;
        }
    }
    let waiting = waiting.expect("a limit of one makes the second request wait");
    drop(stall);
    let out = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("the freed slot serves the waiting GET")
        .unwrap();
    assert!(
        out.starts_with(b"HTTP/1.1 "),
        "{}",
        String::from_utf8_lossy(&out)
    );
    for h in handles {
        h.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn dial_sockets(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<rbitcoin_net::DialRequest>,
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    while let Ok(req) = rx.try_recv() {
        assert_eq!(req.typ, PeerConnType::OutboundFullRelay);
        match req.target {
            rbitcoin_net::DialTarget::Socket(addr) => out.push(addr),
            other => panic!("expected a socket dial, got {other}"),
        }
    }
    out
}

fn book_of(addrs: &[SocketAddr]) -> Arc<std::sync::Mutex<AddrMan>> {
    let mut book = AddrMan::new();
    for addr in addrs {
        book.add(*addr);
    }
    Arc::new(std::sync::Mutex::new(book))
}

/// A live inbound (or any non-quota session) on the first book row must not
/// consume the only open outbound slot forever.
#[test]
fn refill_skips_an_address_that_is_already_live() {
    let peers = rbitcoin_net::PeerHub::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    peers.set_dialer(tx);
    let taken: SocketAddr = "45.1.0.1:18444".parse().unwrap();
    let next: SocketAddr = "45.2.0.1:18444".parse().unwrap();
    let later: SocketAddr = "45.3.0.1:18444".parse().unwrap();
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: bitcoin::p2p::ServiceFlags::NONE,
        timestamp: 0,
        receiver: bitcoin::p2p::Address::new(&taken, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::Address::new(&taken, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 0,
        user_agent: String::new(),
        start_height: 0,
        relay: false,
    };
    let _inbound = peers.register(taken, taken, &ver, true, PeerConnType::Inbound);
    let shared = book_of(&[taken, next, later]);
    let cfg = NodeConfig::default();
    refill_outbound_full_relay(&cfg, &peers, &shared, 1);
    let got = dial_sockets(&mut rx);
    assert_eq!(
        got,
        vec![next],
        "the live inbound address must not be the only candidate for the open slot"
    );
}

/// `--trusted` sets noban. Stale rotation still skips that hub. The book
/// fill does not: an empty noban hub dials up to `--max-outbound`, and a
/// hub already at the cap does not queue another wave.
#[test]
fn trusted_noban_fills_to_max_outbound_and_stops() {
    let peers = rbitcoin_net::PeerHub::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    peers.set_dialer(tx);
    peers.set_noban(true);
    let a: SocketAddr = "45.4.0.1:18444".parse().unwrap();
    let b: SocketAddr = "45.5.0.1:18444".parse().unwrap();
    let shared = book_of(&[a, b]);
    let cfg = NodeConfig::default();
    refill_outbound_full_relay(&cfg, &peers, &shared, 2);
    let got = dial_sockets(&mut rx);
    assert_eq!(got.len(), 2, "--trusted must still dial the book");

    drop(got);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: bitcoin::p2p::ServiceFlags::NONE,
        timestamp: 0,
        receiver: bitcoin::p2p::Address::new(&a, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::Address::new(&a, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 0,
        user_agent: String::new(),
        start_height: 0,
        relay: false,
    };
    let _a = peers.register(a, a, &ver, false, PeerConnType::OutboundFullRelay);
    let _b = peers.register(b, b, &ver, false, PeerConnType::OutboundFullRelay);
    refill_outbound_full_relay(&cfg, &peers, &shared, 2);
    assert!(
        dial_sockets(&mut rx).is_empty(),
        "a noban hub already at --max-outbound must not queue another wave"
    );
}
